package compass

/** Minimal little-endian ELF parser (ELF32/ELF64). No external debugger involved. */
object Elf {

    const val SHT_NULL = 0L
    const val PT_LOAD = 1L

    data class Section(
        val name: String,
        val type: Long,
        val addr: Long,
        val offset: Long,
        val size: Long,
        val data: ByteArray,
    )

    data class Image(
        val is64: Boolean,
        val machine: Int,
        val entry: Long,
        /** Lowest p_vaddr among PT_LOAD segments: the link-time base used for load-bias math. */
        val linkBase: Long,
        val sections: List<Section>,
    ) {
        fun section(name: String): Section? = sections.firstOrNull { it.name == name }
    }

    class ParseException(msg: String) : Exception(msg)

    fun parse(bytes: ByteArray): Image {
        if (bytes.size < 16) throw ParseException("file too small for ELF header")
        if (bytes[0] != 0x7f.toByte() || bytes[1] != 'E'.code.toByte() ||
            bytes[2] != 'L'.code.toByte() || bytes[3] != 'F'.code.toByte()
        ) throw ParseException("not an ELF file")
        val is64 = bytes[4] == 2.toByte()
        if (bytes[5] != 1.toByte()) throw ParseException("only little-endian ELF is supported")
        val r = Reader(bytes)

        r.off = 16
        r.u16() // e_type
        val machine = r.u16()
        r.u32() // e_version
        val entry: Long
        val phoff: Long
        val shoff: Long
        if (is64) {
            entry = r.u64(); phoff = r.u64(); shoff = r.u64()
        } else {
            entry = r.u32(); phoff = r.u32(); shoff = r.u32()
        }
        r.u32() // e_flags
        r.u16() // e_ehsize
        val phentsize = r.u16()
        val phnum = r.u16()
        val shentsize = r.u16()
        val shnum = r.u16()
        val shstrndx = r.u16()

        var linkBase = Long.MAX_VALUE
        for (i in 0 until phnum) {
            val at = phoff + i.toLong() * phentsize
            if (at < 0 || at + phentsize > bytes.size) break
            r.off = at.toInt()
            val pType = r.u32()
            if (is64) {
                r.u32() // p_flags
                val pOffset = r.u64(); val pVaddr = r.u64(); r.u64(); val pFilesz = r.u64()
                if (pType == PT_LOAD && pFilesz > 0) linkBase = minOf(linkBase, pVaddr)
            } else {
                val pOffset = r.u32(); val pVaddr = r.u32(); r.u32(); val pFilesz = r.u32()
                if (pType == PT_LOAD && pFilesz > 0) linkBase = minOf(linkBase, pVaddr)
            }
        }
        if (linkBase == Long.MAX_VALUE) linkBase = 0L

        // Section header string table
        val shdrs = ArrayList<LongArray>()
        for (i in 0 until shnum) {
            val at = shoff + i.toLong() * shentsize
            if (at < 0 || at + shentsize > bytes.size) throw ParseException("section header out of bounds")
            r.off = at.toInt()
            val nameOff = r.u32()
            val type = r.u32()
            val flags: Long; val addr: Long; val offset: Long; val size: Long
            if (is64) {
                flags = r.u64(); addr = r.u64(); offset = r.u64(); size = r.u64()
            } else {
                flags = r.u32(); addr = r.u32(); offset = r.u32(); size = r.u32()
            }
            shdrs.add(longArrayOf(nameOff, type, flags, addr, offset, size))
        }
        fun strAt(strOff: Long, pos: Long): String {
            var p = (strOff + pos).toInt()
            val sb = StringBuilder()
            while (p in bytes.indices && bytes[p] != 0.toByte()) { sb.append(bytes[p].toInt().toChar()); p++ }
            return sb.toString()
        }
        val shstr = if (shstrndx < shdrs.size) shdrs[shstrndx] else null
        val sections = ArrayList<Section>()
        for (sh in shdrs) {
            val name = if (shstr != null) strAt(sh[4], sh[0]) else ""
            val data = if (sh[1] == 8L /* SHT_NOBITS */ || sh[5] == 0L) ByteArray(0)
            else {
                val from = sh[4].toInt()
                val to = (sh[4] + sh[5]).coerceAtMost(bytes.size.toLong()).toInt()
                if (from < 0 || from > bytes.size || to < from) ByteArray(0)
                else bytes.copyOfRange(from, to)
            }
            sections.add(Section(name, sh[1], sh[3], sh[4], sh[5], data))
        }
        return Image(is64, machine, entry, linkBase, sections)
    }
}
